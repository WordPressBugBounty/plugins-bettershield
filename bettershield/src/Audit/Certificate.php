<?php
/**
 * When this site's own TLS certificate stops working.
 *
 * An expired certificate takes a site offline for every visitor and every
 * browser at the same moment, and owners routinely find out from a customer
 * rather than from a tool. It is one of the most total outages a site can
 * have and one of the easiest to see coming, which is an odd combination to
 * leave unwatched.
 *
 * **This is not an external call.** The connection is to this site's own
 * address: a request a site makes
 * to itself never leaves the server, so it engages no third party and needs
 * no guideline-7 disclosure. It reaches no host on `Support\Http`'s allow-list
 * because it reaches no outside host at all.
 *
 * **It never happens on a request somebody is waiting on.** Opening a socket
 * takes as long as it takes, so this runs from the daily task and nowhere
 * else; every reader gets the stored answer. The timeout is short, a failure
 * is a stored "could not check" rather than a finding, and the whole thing is
 * skipped on a site that is not on HTTPS in the first place — where the
 * absence of a certificate is already a louder finding of its own.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Certificate {

	public const OPTION = 'bettershield_certificate';

	/**
	 * How long the socket is given. A certificate check that hangs is worse
	 * than one that does not happen: the task runner has other work.
	 */
	private const TIMEOUT_SECONDS = 5;

	/** Days left at which this stops being a note and starts being a problem. */
	public const SOON     = 21;
	public const URGENT   = 7;
	public const CRITICAL = 2;

	/** How old a remembered expiry may be while today's read is failing. */
	private const STALE_READ_SECONDS = 7 * DAY_IN_SECONDS;

	/**
	 * Look now, and store what was found. Called by the daily task.
	 */
	public static function check(): void {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );

		if ( '' === $host || ! self::site_is_https() ) {
			// Only where there is something to remove: on a site that has
			// never been on HTTPS this ran every day against a key that was
			// never written.
			if ( false !== get_option( self::OPTION, false ) ) {
				delete_option( self::OPTION );
			}

			return;
		}

		$read    = self::read_certificate( $host );
		$expires = null === $read ? null : $read['expires'];
		$previous = get_option( self::OPTION, array() );
		$previous = is_array( $previous ) ? $previous : array();
		// A failed connection does not renew a certificate or erase its expiry.
		$same_host    = ( $previous['host'] ?? $host ) === $host;
		$known_expiry = $same_host ? ( $previous['expires_at'] ?? null ) : null;

		// When the expiry kept above was last actually read. A record from
		// before this was kept dates its read by its own look, if that look
		// succeeded.
		$last_read = null;
		if ( null !== $expires ) {
			$last_read = time();
		} elseif ( $same_host ) {
			$last_read = $previous['last_read_at'] ?? ( false !== ( $previous['reliable'] ?? true ) ? ( $previous['checked_at'] ?? null ) : null );
		}

		update_option(
			self::OPTION,
			array(
				// When this last looked, which is the one thing worth saying
				// beside a certificate that could not be read.
				'checked_at' => time(),
				// Retain the last known expiry when the new read fails;
				// reliable describes this attempt, not the retained evidence.
				'expires_at' => $expires ?? $known_expiry,
				'host' => $host,
				'reliable' => null !== $expires,
				'last_read_at' => null === $last_read ? null : (int) $last_read,
				// Who issued it, for the CAA record the domain Fix proposes
				// (#2203). The organization's name only.
				'issuer' => null === $read ? ( $same_host ? ( $previous['issuer'] ?? '' ) : '' ) : $read['issuer'],
			),
			false
		);
	}

	/**
	 * Days until the stored expiry, or null when there is nothing to say.
	 */
	public static function days_left(): ?int {
		$stored = get_option( self::OPTION, array() );

		if ( ! is_array( $stored ) || null === ( $stored['expires_at'] ?? null ) ) {
			return null;
		}

		/*
		 * An expiry kept from an earlier read while today's failed. Kept so
		 * one bad day does not close a real warning — but certificates renew
		 * well before they lapse, so once the remembered date has passed, or
		 * the read is more than a week old, it describes a certificate that
		 * has most likely been replaced. Reported as an expired one, a host
		 * that cannot reach itself had a made-up outage at critical.
		 */
		if ( false === ( $stored['reliable'] ?? true ) ) {
			$last_read = isset( $stored['last_read_at'] ) ? (int) $stored['last_read_at'] : null;

			if ( (int) $stored['expires_at'] < time() || ( null !== $last_read && time() - $last_read > self::STALE_READ_SECONDS ) ) {
				return null;
			}
		}

		return (int) floor( ( (int) $stored['expires_at'] - time() ) / DAY_IN_SECONDS );
	}

	/**
	 * How loudly to say it.
	 *
	 * Rising rather than a single threshold, because "in three weeks" and "on
	 * Tuesday" are different messages and a tool that sends the same one for
	 * both gets filtered.
	 */
	public static function severity_for( int $days ): string {
		if ( $days < 0 ) {
			return 'critical';
		}

		if ( $days <= self::CRITICAL ) {
			return 'critical';
		}

		if ( $days <= self::URGENT ) {
			return 'high';
		}

		return 'medium';
	}

	/**
	 * Whether this site is served over HTTPS at all.
	 *
	 * The question is about the address the site hands out, not about how the
	 * current request arrived, and the two disagree on every site whose
	 * encryption ends at a proxy. One answer, in one place, so a second copy
	 * of it cannot drift into asking the other question.
	 */
	public static function site_is_https(): bool {
		return Server::address_is_https();
	}

	/**
	 * The organization that issued the certificate the site last served, or
	 * an empty string where it was never read.
	 */
	public static function issuer(): string {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? (string) ( $stored['issuer'] ?? '' ) : '';
	}

	/**
	 * The certificate's expiry and issuer, read from this site's own socket.
	 *
	 * @return array{expires: int, issuer: string}|null Null if it could not be read.
	 */
	private static function read_certificate( string $host ): ?array {
		if ( ! function_exists( 'openssl_x509_parse' ) || ! function_exists( 'stream_socket_client' ) ) {
			return null;
		}

		$port = (int) ( wp_parse_url( home_url(), PHP_URL_PORT ) ?? 443 );
		$port = $port > 0 ? $port : 443;

		$context = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					// Reading the expiry, not judging the chain: a site with a
					// certificate this server does not trust still has one with
					// a date on it, and that date is what is being asked for.
					// Verification failures are the browser's business and the
					// audit's HTTPS check already covers the rest.
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);

		$errno  = 0;
		$errstr = '';

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a site this server cannot reach from inside is a stored "could not check", never a warning printed into a dashboard.
		$socket = @stream_socket_client(
			'ssl://' . $host . ':' . $port,
			$errno,
			$errstr,
			self::TIMEOUT_SECONDS,
			STREAM_CLIENT_CONNECT,
			$context
		);

		if ( false === $socket ) {
			return null;
		}

		$params = stream_context_get_params( $socket );
		fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

		$certificate = $params['options']['ssl']['peer_certificate'] ?? null;

		if ( null === $certificate ) {
			return null;
		}

		$parsed = openssl_x509_parse( $certificate );

		if ( ! is_array( $parsed ) || ! isset( $parsed['validTo_time_t'] ) ) {
			return null;
		}

		return array(
			'expires' => (int) $parsed['validTo_time_t'],
			'issuer'  => isset( $parsed['issuer']['O'] ) && is_string( $parsed['issuer']['O'] ) ? \BetterShield\Support\Text::clip( $parsed['issuer']['O'], 120 ) : '',
		);
	}
}
